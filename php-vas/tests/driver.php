<?
    /* This script is run by driver before any test script */

    error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE);
    if (!extension_loaded("vas"))
	dl("vas.so");

?>

