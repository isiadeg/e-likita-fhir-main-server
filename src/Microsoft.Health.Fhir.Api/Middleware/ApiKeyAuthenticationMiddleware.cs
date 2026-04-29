// -------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// -------------------------------------------------------------------------------------------------

using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Microsoft.Health.Fhir.Api.Middleware
{
    public class ApiKeyAuthenticationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;
        private readonly ILogger<ApiKeyAuthenticationMiddleware> _logger;
        private const string ApiKeyHeader = "X-Elikita-Internal-Key";

        public ApiKeyAuthenticationMiddleware(
            RequestDelegate next,
            IConfiguration configuration,
            ILogger<ApiKeyAuthenticationMiddleware> logger)
        {
            _next = next;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path.Value?.ToLower(CultureInfo.InvariantCulture) ?? string.Empty;

            // Allow health check and metadata endpoints without API key
            if (path.Contains("/health", StringComparison.OrdinalIgnoreCase) ||
                path.Contains("/metadata", StringComparison.OrdinalIgnoreCase))
            {
                await _next(context);
                return;
            }

            foreach (var header in context.Request.Headers)
            {
            }

            // Check for API key in header
            if (!context.Request.Headers.TryGetValue(ApiKeyHeader, out var extractedApiKey))
            {
                _logger.LogWarning($"API Key missing from request. Path: {path}, IP: {context.Connection.RemoteIpAddress}");
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(@"{""error"": ""Unauthorized"", ""message"": ""API Key missing""}");
                return;
            }

            // Validate API key
            var expectedApiKey = _configuration["FhirServer:InternalApiKey"];

            if (string.IsNullOrEmpty(expectedApiKey))
            {
                _logger.LogError("FhirServer:InternalApiKey not configured in appsettings");
                context.Response.StatusCode = 500;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(@"{""error"": ""Server Error"", ""message"": ""Server configuration error""}");
                return;
            }

            var keysMatch = expectedApiKey.Equals(extractedApiKey, StringComparison.Ordinal);

            if (!keysMatch)
            {
                // Character-by-character comparison for debugging
                _logger.LogWarning("KEY MISMATCH DETAILS:");
                _logger.LogWarning($"  Expected length: {expectedApiKey.Length}, Received length: {extractedApiKey.ToString().Length}");

                // Show first/last few characters for debugging (don't log full keys in production!)
                if (expectedApiKey.Length > 10 && extractedApiKey.ToString().Length > 10)
                {
                    _logger.LogWarning($"  Expected starts with: {expectedApiKey.Substring(0, 10)}...");
                    _logger.LogWarning($"  Received starts with: {extractedApiKey.ToString().Substring(0, 10)}...");
                }

                _logger.LogWarning($"Invalid API Key provided. Path: {path}, IP: {context.Connection.RemoteIpAddress}");
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(@"{""error"": ""Unauthorized"", ""message"": ""Invalid API Key""}");
                return;
            }

            // Optional: Verify request is from allowed IP addresses
            var allowedIps = _configuration.GetSection("FhirServer:AllowedIPs").Get<string[]>();
            if (allowedIps != null && allowedIps.Length > 0)
            {
                var remoteIp = context.Connection.RemoteIpAddress?.ToString();
                if (!allowedIps.Contains(remoteIp, StringComparer.Ordinal))
                {
                    _logger.LogWarning($"Request with valid API key from unauthorized IP: {remoteIp}");
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(@"{""error"": ""Forbidden"", ""message"": ""Invalid request origin""}");
                    return;
                }
            }

            // Create authenticated user for API key requests
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, "ApiKeyClient"),
                new Claim(ClaimTypes.NameIdentifier, "internal-service"),
                new Claim("AuthenticationType", "ApiKey"),
            };
            var identity = new ClaimsIdentity(claims, "ApiKey");
            var principal = new ClaimsPrincipal(identity);
            context.User = principal;

            await _next(context);
        }
    }
}
