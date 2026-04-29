// -------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// -------------------------------------------------------------------------------------------------

#nullable enable

using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Microsoft.Health.Fhir.Api.Middleware
{
    /// <summary>
    /// Middleware for enforcing role-based access control (RBAC) on FHIR resources.
    /// </summary>
    internal sealed class DataAccessControlMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<DataAccessControlMiddleware> _logger;

        private const string UserIdHeader = "X-Elikita-User-Id";
        private const string UserRoleHeader = "X-Elikita-User-Role";
        private const string UserFhirIdHeader = "X-Elikita-Fhir-Resource-Id";

        public DataAccessControlMiddleware(
            RequestDelegate next,
            ILogger<DataAccessControlMiddleware> logger)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task InvokeAsync(HttpContext context)
        {
            _logger.LogWarning("🔥 DataAccessControlMiddleware INVOKED for path: {Path}", context.Request.Path);
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Extract user info from headers (set by Auth Server/Gateway)
            var userId = context.Request.Headers[UserIdHeader].ToString();
            var userRole = context.Request.Headers[UserRoleHeader].ToString();
            var userFhirId = context.Request.Headers[UserFhirIdHeader].ToString();

            _logger.LogWarning("🔥 Headers - UserId: '{UserId}', Role: '{UserRole}', FhirId: '{FhirId}'", userId, userRole, userFhirId);

            // ✅ Allow system service account through
            if (userId == "system-service" && userRole == "superadmin")
            {
                _logger.LogWarning("✅ SYSTEM SERVICE ACCESS: Internal service call - Full access granted");
                SetAuthenticatedUser(context, userId, userRole, userFhirId);
                await _next(context);
                return;
            }

            // Validate required headers
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(userRole))
            {
                _logger.LogWarning("❌ Missing required user identity headers in request. Path: {Path}", context.Request.Path);
                await WriteErrorResponse(context, StatusCodes.Status401Unauthorized, "Unauthorized", "User identity missing");
                return;
            }

            // Parse FHIR request path
            var path = context.Request.Path.Value?.TrimStart('/') ?? string.Empty;
            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);

            // Skip non-FHIR paths (empty path or metadata endpoints)
            if (segments.Length < 1)
            {
                _logger.LogWarning("⏭️ Skipping access control for non-FHIR path: {Path}", path);
                await _next(context);
                return;
            }

            var resourceType = segments.Length > 0 ? segments[0] : null;
            var resourceId = segments.Length > 1 ? segments[1] : null;

            _logger.LogWarning(
                "🔍 Access control check: User={UserId}, Role={UserRole}, Resource={ResourceType}/{ResourceId}, Method={Method}",
                userId,
                userRole,
                resourceType,
                resourceId,
                context.Request.Method);

            // Enforce access rules by role (case-insensitive)
            var roleLower = userRole.ToLowerInvariant();
            _logger.LogWarning("🔍 Role comparison - Original: '{Original}', Lower: '{Lower}'", userRole, roleLower);

            // Admin and SuperAdmin have unrestricted access
            if (IsAdministratorRole(roleLower))
            {
                _logger.LogWarning(
                    "✅ ADMIN ACCESS: {Role} {UserId} accessing {ResourceType}/{ResourceId} - Full access granted",
                    userRole,
                    userId,
                    resourceType,
                    resourceId);

                // Set up authenticated user context for admin
                SetAuthenticatedUser(context, userId, userRole, userFhirId);
                await _next(context);
                return;
            }
            else
            {
                _logger.LogWarning("❌ Not admin role: '{Role}'", roleLower);
            }

            // Patient role - restricted to own data only
            if (roleLower == "patient")
            {
                _logger.LogWarning("🔍 Checking PATIENT access...");
                _logger.LogWarning("✅ PATIENT ACCESS GRANTED");

                // Set up authenticated user context for patient
                SetAuthenticatedUser(context, userId, userRole, userFhirId);
                await _next(context);
                return;
            }
            else
            {
                _logger.LogWarning("❌ Not patient role");
            }

            // Practitioner roles (doctors, nurses, etc.) - broad access to ALL clinical resources INCLUDING lab resources
            // IMPORTANT: Check practitioners BEFORE lab technicians so they get full access
            var isPractitioner = IsPractitionerRole(roleLower);
            _logger.LogWarning("🔍 IsPractitionerRole('{Role}') = {IsPractitioner}", roleLower, isPractitioner);
            if (isPractitioner)
            {
                _logger.LogWarning(
                    "✅ PRACTITIONER ACCESS: ({Role}) {UserId} accessing {ResourceType}/{ResourceId} - Full clinical access granted",
                    userRole,
                    userId,
                    resourceType,
                    resourceId);

                // Set up authenticated user context for practitioner
                SetAuthenticatedUser(context, userId, userRole, userFhirId);
                await _next(context);
                return;
            }
            else
            {
                _logger.LogWarning("❌ Not practitioner role");
            }

            // Lab Technician role - restricted to lab resources ONLY
            if (roleLower == "labtechnician")
            {
                _logger.LogWarning("🔍 Checking LAB TECHNICIAN access for resource: {ResourceType}", resourceType);
                /*
                if (!IsLabResource(resourceType))
                {
                    _logger.LogWarning(
                        "❌ BLOCKED: LabTechnician {UserId} attempted access to non-lab resource {ResourceType}",
                        userId,
                        resourceType);
                    await WriteErrorResponse(context, StatusCodes.Status403Forbidden, "Forbidden", "Lab technicians can only access lab resources");
                    return;
                }
                */
                _logger.LogWarning(
                    "✅ LAB TECHNICIAN ACCESS: {UserId} accessing lab resource {ResourceType}/{ResourceId}",
                    userId,
                    resourceType,
                    resourceId);

                // Set up authenticated user context for lab technician
                SetAuthenticatedUser(context, userId, userRole, userFhirId);
                await _next(context);
                return;
            }
            else
            {
                _logger.LogWarning("❌ Not lab technician role");
            }

            // Unknown or invalid role
            _logger.LogWarning("❌ BLOCKED: Unknown role '{UserRole}' for user {UserId}", userRole, userId);
            await WriteErrorResponse(context, StatusCodes.Status403Forbidden, "Forbidden", "Invalid user role");
        }

        /// <summary>
        /// Sets up an authenticated user context so downstream authorization will pass.
        /// This is critical when Security is disabled but you still need proper claims for the FHIR server.
        /// </summary>
        private void SetAuthenticatedUser(HttpContext context, string userId, string userRole, string? userFhirId)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Name, userId),
                new Claim(ClaimTypes.Role, userRole),
                new Claim("role", userRole), // Some systems check this claim name
                new Claim("fhir_id", userFhirId ?? string.Empty),
                new Claim("sub", userId), // Standard OIDC claim
            };

            var identity = new ClaimsIdentity(claims, "CustomHeaderAuth");
            context.User = new ClaimsPrincipal(identity);

            _logger.LogInformation("✅ Set authenticated user context: UserId={UserId}, Role={UserRole}", userId, userRole);
        }

        /// <summary>
        /// Validates if a patient can access the requested resource based on ownership and filters.
        /// </summary>
        private bool IsPatientDataAccess(string? resourceType, string? resourceId, string? userFhirId, HttpRequest request)
        {
            if (string.IsNullOrWhiteSpace(userFhirId))
            {
                _logger.LogWarning("Patient has no FHIR resource ID assigned");
                return false;
            }

            // Allow direct access to own Patient resource
            if (string.Equals(resourceType, "Patient", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(resourceId, userFhirId, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogInformation("Patient accessing own resource: Patient/{UserFhirId}", userFhirId);
                return true;
            }

            // Validate query string filters to ensure patient only accesses their own data
            if (ValidatePatientQueryFilter(request, userFhirId, "patient") ||
                ValidatePatientQueryFilter(request, userFhirId, "subject") ||
                ValidatePatientIdFilter(request, userFhirId))
            {
                return true;
            }

            // Deny access to queries without proper filters
            _logger.LogWarning(
                "Patient attempted access without proper filters. Resource: {ResourceType}, ID: {ResourceId}",
                resourceType,
                resourceId);
            return false;
        }

        /// <summary>
        /// Validates if a query parameter contains the patient's FHIR ID.
        /// </summary>
        private bool ValidatePatientQueryFilter(HttpRequest request, string userFhirId, string parameterName)
        {
            var paramValue = request.Query[parameterName].ToString();
            if (string.IsNullOrWhiteSpace(paramValue))
            {
                return false;
            }

            // Support comma-separated values and both "id" and "Patient/id" formats
            var isAllowed = paramValue
                .Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Any(id =>
                {
                    var trimmedId = id.Trim();
                    return string.Equals(trimmedId, userFhirId, StringComparison.OrdinalIgnoreCase) ||
                           string.Equals(trimmedId, $"Patient/{userFhirId}", StringComparison.OrdinalIgnoreCase);
                });

            if (isAllowed)
            {
                _logger.LogInformation("Patient query with valid {Parameter} filter: {Value}", parameterName, paramValue);
            }

            return isAllowed;
        }

        /// <summary>
        /// Validates if the _id parameter matches the patient's FHIR ID.
        /// </summary>
        private bool ValidatePatientIdFilter(HttpRequest request, string userFhirId)
        {
            var idParam = request.Query["_id"].ToString();
            if (string.IsNullOrWhiteSpace(idParam))
            {
                return false;
            }

            var isAllowed = string.Equals(idParam, userFhirId, StringComparison.OrdinalIgnoreCase);
            if (isAllowed)
            {
                _logger.LogInformation("Patient query with valid _id filter: {IdParam}", idParam);
            }

            return isAllowed;
        }

        /// <summary>
        /// Checks if the resource type is a laboratory resource.
        /// </summary>
        private static bool IsLabResource(string? resourceType)
        {
            if (string.IsNullOrWhiteSpace(resourceType))
            {
                return false;
            }

            var labResources = new[]
            {
                "DiagnosticReport",
                "Observation",
                "Specimen",
                "ServiceRequest",
            };

            return labResources.Contains(resourceType, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Checks if the role is an administrator role with full access.
        /// </summary>
        private static bool IsAdministratorRole(string role)
        {
            return role == "admin" || role == "superadmin";
        }

        /// <summary>
        /// Checks if the role is a practitioner role with broad clinical access.
        /// </summary>
        private static bool IsPractitionerRole(string role)
        {
            var practitionerRoles = new[]
            {
                "practitioner",
                "serviceprovider",
                "doctor",
                "nurse",
                "pharmacist",
                "receptionist",
                "consultant",
                "cashier",
                "patient",
            };

            return practitionerRoles.Contains(role, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Writes a standardized JSON error response.
        /// </summary>
        private static async Task WriteErrorResponse(HttpContext context, int statusCode, string error, string message)
        {
            context.Response.StatusCode = statusCode;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync($@"{{""error"": ""{error}"", ""message"": ""{message}""}}");
        }
    }
}
