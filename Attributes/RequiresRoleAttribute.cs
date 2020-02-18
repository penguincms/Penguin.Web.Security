using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Penguin.Security.Abstractions.Constants;
using Penguin.Security.Abstractions.Exceptions;
using Penguin.Security.Abstractions.Extensions;
using Penguin.Security.Abstractions.Interfaces;
using Penguin.Web.Security.Results;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace Penguin.Web.Security.Attributes
{
    /// <summary>
    /// Used to denote that a Controller Action should require the session user to have any role matching the provided in order to access it
    /// </summary>
    [SuppressMessage("Design", "CA1056:Uri properties should not be strings")]
    public sealed class RequiresRoleAttribute : ActionFilterAttribute, IActionFilter
    {
        private const string NO_USER_SESSION = "IUserSession was not able to be resolved by the internal service provider";

        /// <summary>
        /// The roles allowed by this attribute
        /// </summary>
        public List<string> AllowedRoles { get; }

        /// <summary>
        /// Mark the Controller Action as only being accessible to users with any of the provided roles
        /// </summary>
        /// <param name="roleNames"></param>
        public RequiresRoleAttribute(params string[] roleNames)
        {
            this.AllowedRoles = roleNames.ToList();
        }

        /// <summary>
        /// Evaluates the user session against the roles provided at construction
        /// </summary>
        /// <param name="userSession">The user session to evaluate</param>
        /// <returns>The result of the evaluation</returns>
        public RequiresRoleResult Evaluate(IUserSession userSession)
        {
            if (userSession is null)
            {
                throw new System.ArgumentNullException(nameof(userSession));
            }

            IHasGroupsAndRoles loggedInUser = userSession.LoggedInUser;

            if (userSession.IsLocalConnection)
            {
                return RequiresRoleResult.Authorized;
            }
            if (userSession is null || !userSession.IsLoggedIn)
            {
                return RequiresRoleResult.Login;
            }
            else if (!this.AllowedRoles.Any(r => loggedInUser.HasRole(r)) && !loggedInUser.HasRole(RoleNames.SysAdmin))
            {
                return RequiresRoleResult.Unauthorized;
            }
            else
            {
                return RequiresRoleResult.Authorized;
            }
        }

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

            RequiresRoleResult evaluation = this.Evaluate(userSession);

            if (evaluation == RequiresRoleResult.Login)
            {
                throw new NotLoggedInException();
            }
            else if (evaluation == RequiresRoleResult.Unauthorized)
            {
                throw new MissingRoleException(AllowedRoles.ToArray());
            }
            else
            {
                base.OnActionExecuting(filterContext);
            }
        }
    }
}