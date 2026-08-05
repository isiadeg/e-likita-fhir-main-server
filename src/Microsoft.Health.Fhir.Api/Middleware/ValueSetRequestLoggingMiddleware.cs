// -------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// -------------------------------------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;

namespace Microsoft.Health.Fhir.Api.Middleware
{
    public class ValuesetRequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ValuesetRequestLoggingMiddleware> _logger;

        public ValuesetRequestLoggingMiddleware(RequestDelegate next, ILogger<ValuesetRequestLoggingMiddleware> logger)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path.Value ?? string.Empty;
            if (path.Contains("valueset", StringComparison.OrdinalIgnoreCase))
            {
                var fullUrl = context.Request.GetDisplayUrl();
                _logger.LogWarning("Valueset request received: {FullUrl}", fullUrl);
            }

            await _next(context);
        }
    }
}
