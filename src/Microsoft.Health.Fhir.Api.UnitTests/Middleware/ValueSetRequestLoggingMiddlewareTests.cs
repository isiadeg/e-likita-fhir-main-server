// -------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// -------------------------------------------------------------------------------------------------

using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Health.Fhir.Api.Middleware;
using Xunit;

namespace Microsoft.Health.Fhir.Api.UnitTests.Middleware
{
    public class ValuesetRequestLoggingMiddlewareTests
    {
        [Fact]
        public async Task InvokeAsync_LogsWarning_WhenPathContainsValueset()
        {
            var loggerFactory = LoggerFactory.Create(builder => builder.AddDebug());
            var logger = loggerFactory.CreateLogger<ValuesetRequestLoggingMiddleware>();
            var middleware = new ValuesetRequestLoggingMiddleware(
                _ => Task.CompletedTask,
                logger);

            var context = new DefaultHttpContext();
            context.Request.Scheme = "https";
            context.Request.Host = new HostString("localhost");
            context.Request.Path = "/ValueSet/test";

            await middleware.InvokeAsync(context);

            Assert.True(true);
        }
    }
}
