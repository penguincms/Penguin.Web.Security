using System;
using System.Collections.Generic;
using System.Text;

namespace Penguin.Cms.Web.Security.Attributes.Results
{
    /// <summary>
    /// The results of checking permissions against the provided user session
    /// </summary>
    public enum RequiresRoleResult
    {
        /// <summary>
        /// There is no active user session
        /// </summary>
        Login,

        /// <summary>
        /// There is an active user session but the user does not have the required permissions
        /// </summary>
        Unauthorized,

        /// <summary>
        /// There is an active user session any the user has the required persmission
        /// </summary>
        Authorized
    }
}