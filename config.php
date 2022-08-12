<?php 

    //Session Configuration
    defined('DS') or define('DS' , DIRECTORY_SEPARATOR);
    defined('SESSION_SAVE_PATH')        ? null : define ('SESSION_SAVE_PATH', dirname(realpath(__FILE__)) . DS . "sessions");
