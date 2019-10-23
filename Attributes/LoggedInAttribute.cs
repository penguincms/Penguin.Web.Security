using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Penguin.Security.Abstractions.Exceptions;
using Penguin.Security.Abstractions.Interfaces;
using System;

namespace Penguin.Web.Security.Attributes
{
    /// <summary>
    /// Requires an active logged in user session to access the controller action
    /// </summary>
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
    public class LoggedInAttribute : ActionFilterAttribute, IActionFilter
    {
        private const string NO_USER_SESSION = "IUserSession was not able to be resolved by the internal service provider";

        /// <summary>
        /// Executes the action filter against the provided filter context
        /// </summary>
        /// <param name="filterContext">The filter context to execture against</param>
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (filterContext is null)
            {
                throw new ArgumentNullException(nameof(filterContext));
            }

            IUserSession userSession = filterContext.HttpContext.RequestServices.GetService<IUserSession>();

            if (userSession is null)
            {
                throw new Exception(NO_USER_SESSION);
            }

            if (!userSession.IsLoggedIn)
            {
                throw new NotLoggedInException();
            }

            base.OnActionExecuting(filterContext);
        }
    }
}