<?php
require_once("config.php");
require_once("Query.php");
?>

<html>
<head>
    <title>
    </title>
    <script>
        function autoRefresh() {
            window.location = window.location.href;
        }
        setInterval('autoRefresh()', 5000);
    </script>
</head>
</html>