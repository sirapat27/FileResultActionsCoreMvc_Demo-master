using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Primitives;

namespace FileResultActionsCoreMvc_Demo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public sealed class SecurityHeadersMiddleware
        {
            private readonly RequestDelegate _next;

            public SecurityHeadersMiddleware(RequestDelegate next)
            {
                _next = next;
            }

            public Task Invoke(HttpContext context)
            {
                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
                // TODO Change the value depending of your needs
                context.Response.Headers.Add("referrer-policy", new StringValues("strict-origin-when-cross-origin"));

                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
                context.Response.Headers.Add("x-content-type-options", new StringValues("nosniff"));

                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
                context.Response.Headers.Add("x-frame-options", new StringValues("DENY"));

                // https://security.stackexchange.com/questions/166024/does-the-x-permitted-cross-domain-policies-header-have-any-benefit-for-my-websit
                context.Response.Headers.Add("X-Permitted-Cross-Domain-Policies", new StringValues("none"));

                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
                context.Response.Headers.Add("x-xss-protection", new StringValues("1; mode=block"));

                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT
                // You can use https://report-uri.com/ to get notified when a misissued certificate is detected
                context.Response.Headers.Add("Expect-CT", new StringValues("max-age=0, enforce, report-uri=\"https://example.report-uri.com/r/d/ct/enforce\""));

                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy
                // https://github.com/w3c/webappsec-feature-policy/blob/master/features.md
                // https://developers.google.com/web/updates/2018/06/feature-policy
                // TODO change the value of each rule and check the documentation to see if new features are available
                context.Response.Headers.Add("Feature-Policy", new StringValues(
                    "accelerometer 'none';" +
                    "ambient-light-sensor 'none';" +
                    "autoplay 'none';" +
                    "battery 'none';" +
                    "camera 'none';" +
                    "display-capture 'none';" +
                    "document-domain 'none';" +
                    "encrypted-media 'none';" +
                    "execution-while-not-rendered 'none';" +
                    "execution-while-out-of-viewport 'none';" +
                    "gyroscope 'none';" +
                    "magnetometer 'none';" +
                    "microphone 'none';" +
                    "midi 'none';" +
                    "navigation-override 'none';" +
                    "payment 'none';" +
                    "picture-in-picture 'none';" +
                    "publickey-credentials-get 'none';" +
                    "sync-xhr 'none';" +
                    "usb 'none';" +
                    "wake-lock 'none';" +
                    "xr-spatial-tracking 'none';"
                    ));

                // https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
                // TODO change the value of each rule and check the documentation to see if new rules are available
                context.Response.Headers.Add("Content-Security-Policy", new StringValues(
                    "base-uri 'none';" +
                     // "block-all-mixed-content;" +
                     // "child-src 'none';" +
                     // "connect-src 'none';" +
                     // //"default-src 'none';" +               //use
                     // "font-src 'none';" +
                     // "form-action 'none';" +
                     // "frame-ancestors 'none';" +
                     // "frame-src 'none';" +
                     // "img-src 'none';" +
                     // "manifest-src 'none';" +
                     // "media-src 'none';" +
                     // "object-src 'none';" +
                     // //"sandbox;" +                          //use
 //                    "script-src 'none';" +                //use
                                                           //// "script-src-attr 'none';" +
                                                           // //"script-src-elem 'none';" +           //use
                                                           //"style-src 'none';" +
                                                           //"style-src-attr 'none';" +
                                                           //"style-src-elem 'none';" +
                    "upgrade-insecure-requests;" +
                    "worker-src 'none';"
                    ));

                return _next(context);
            }
        }
        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            services.AddSession(options =>
            {
                // Set a short timeout for easy testing.
                options.IdleTimeout = TimeSpan.FromMinutes(5);
                options.Cookie.HttpOnly = true;
            });

            ////config ip limite=========================================================================================
            //// needed to load configuration from appsettings.json
            services.AddOptions();

            //// needed to store rate limit counters and ip rules
            services.AddMemoryCache();

            ////load general configuration from appsettings.json
            //services.Configure<IpRateLimitOptions>(Configuration.GetSection("IpRateLimiting"));

            ////// inject counter and rules stores
            //services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
            //services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();

            //// Add framework services.
            services.AddMvc();

            //// https://github.com/aspnet/Hosting/issues/793
            //// the IHttpContextAccessor service is not registered by default.
            //// the clientId/clientIp resolvers use it.
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            //// configuration (resolvers, counter key builders)
            //services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
            ////============================================================================= ip limit==================

            //// Configure HSTS
            //// https://aka.ms/aspnetcore-hsts
            //// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
            services.AddHsts(options =>
            {
                options.MaxAge = TimeSpan.FromDays(90);
                options.IncludeSubDomains = true;
                options.Preload = true;
            });

            ////Configure HTTPS redirection
            services.AddHttpsRedirection(options =>
            {
                options.RedirectStatusCode = StatusCodes.Status301MovedPermanently;
                options.HttpsPort = 443;
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseMiddleware<SecurityHeadersMiddleware>();
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
