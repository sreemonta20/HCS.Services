﻿namespace HCS.Security.Helper
{
    /// <summary>
    /// It stores all the constants which are currently being used throughout the project.
    /// </summary>
    public class ConstantSupplier
    {
        #region Common Constants
        public const string REQUIRED_PARAMETER_NOT_EMPTY = "Required Parameters Should Not Empty Or Null";
        public const string CORSS_POLICY_NAME = "AllowRedirectOrigin";
        public const string APP_SETTINGS_FILE_NAME = "appsettings.json";
        public const string SECURITY_SQL_DB_CONNECTION_STRING_NAME = "SecurityConectionString";
        public const string AUTHORIZATION_TOKEN_TYPE = "bearer";
        public const string AUTHORIZATION_TOKEN_HEADER_ADD_NAME_01 = "token-expired";
        public const string AUTHORIZATION_TOKEN_HEADER_ADD_VALUE_01 = "true";
        public const string EMAIL_CONFIG_CLASS_KEY = "EmailConfiguration";

        public const string SWAGGER_HCS_API_SERVICE_DOC_VERSION_NAME = "v1";
        public const string SWAGGER_HCS_API_SERVICE_DOC_TITLE = "HCS Services API";
        public const string SWAGGER_HCS_API_SERVICE_DOC_DESCRIPTION = "HCS Services API";
        public const string SWAGGER_HCS_API_SERVICE_DOC_CONTACT_NAME = "Healthcare Solutions ";
        public const string SWAGGER_HCS_API_SERVICE_DOC_CONTACT_EMAIL = "info@hcs.com";
        public const string SWAGGER_HCS_API_SERVICE_DOC_CONTACT_URL = "https://www.hcs.ae/";
        public const string SWAGGER_HCS_API_SERVICE_DOC_SCHEME_DESC = "Authorization header using the Bearer scheme. Example: {token}";
        public const string SWAGGER_HCS_API_SERVICE_DOC_SCHEME_NAME = "Authorization";
        public const string SWAGGER_HCS_API_SERVICE_DOC_SCHEME_SCHEME = "bearer";
        public const string SWAGGER_HCS_API_SERVICE_DOC_SCHEME_REF_ID = "Bearer";

        public const string SWAGGER_HCS_API_SERVICE_DOC_END_POINT = "/swagger/v1/swagger.json";
        public const string SWAGGER_HCS_API_SERVICE_DOC_END_POINT_NAME = "HCS Services API v1";
        #endregion

        #region Serilog Related
        public const string LOG_INFO_APP_START_MSG = "Application is starting";
        public const string LOG_FATAL_APP_FAILED_MSG = "Fatal: Application error";
        public const string LOG_INFO_APPEND_LINE_FIRST = "**********************************************************************";
        public const string LOG_INFO_APPEND_LINE_SECOND_GATEWAY = "**                      HCS Services                                **";
        public const string LOG_INFO_APPEND_LINE_THIRD_VERSION = "**                    [Version 1.0.0]                               **";
        public const string LOG_INFO_APPEND_LINE_FOURTH_COPYRIGHT = "**  ©2022-2023 Health Care Solutions. All rights reserved           **";
        public const string LOG_INFO_APPEND_LINE_END = "**********************************************************************";

        //api/User/login
        public const string LOGIN_STARTED_INFO_MSG = "Login api method started.\n";
        public const string LOGIN_REQ_MSG = "Login api method request is: \n{0}\n";
        public const string LOGIN_EXCEPTION_MSG = "Exception is: \t\t\t{0}\nResponse is: \n{1}\n";
        public const string SERVICE_LOGIN_REQ_MSG = "Authenticate (User service) method request is: \n{0}\n";
        public const string SERVICE_LOGIN_FAILED_MSG = "Response is: \n{1}\n";
        public const string SERVICE_LOGIN_RES_MSG = "Authenticate (User service) method response is: \n{0}\n";
        public const string LOGIN_RES_MSG = "Login api method response is: \n{0}\n";
        #endregion


        #region User Service
        public const string ADMIN = "Admin";
        public const string USER = "User";

        public const string GET_USER_FAILED = "Fetching user details failed.";
        public const string GET_USER_SUCCESS = "Fetching user details successful";

        public const string GET_USER_LIST_FAILED = "Fetching user list failed.";
        public const string GET_USER_LIST_SUCCESS = "Fetching user list successful";

        public const string AUTH_FAILED = "Authentation failed. Please try again later";
        public const string AUTH_INVALID_CREDENTIAL = "Invalid credential";
        public const string AUTH_SUCCESS = "Authentation success!";
        public const string AUTH_FAILED_ATTEMPT = "Your account was blocked for a {0} minutes, please try again later.";

        public const string SAVE_KEY = "Save";
        public const string UPDATE_KEY = "Update";

        public const string REG_USER_SAVE_FAILED = "Registering user details failed. Please try again later";
        public const string REG_USER_SAVE_SUCCESS = "Registering user details success!";

        public const string REG_USER_UPDATE_FAILED = "Updating user details failed. Please try again later";
        public const string REG_USER_UPDATE_SUCCESS = "Updating user details success!";

        public const string EXIST_USER = "User is already exist. Try unique username";

        public const string DELETE_FAILED = "Deletion of user failed!. Please try again later";
        public const string DELETE_SUCCESS = "User deleted successfully";
        #endregion

        #region User Controller
        public const string USER_CTRLER_ROUTE_NAME = "api/[controller]";
        public const string GET_USER_ROUTE_NAME = "getUserbyId";
        public const string GET_ALL_USER_ROUTE_NAME = "getAllUsers";
        public const string POST_AUTH_ROUTE_NAME = "login";
        public const string POST_PUT_USER_ROUTE_NAME = "registerUser";
        public const string DEL_USER_ROUTE_NAME = "deleteUser";

        #endregion

    }
}
