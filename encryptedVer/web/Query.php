<?php
require_once("config.php");
?>
<h2>Login Tracking</h2>
<?php 
$db = get_pdo_connection();
$query = false;
$loop = true;
// Query the database



$query = $db->prepare(<<<'EOD'

SELECT d1.*
FROM device_status_log d1
JOIN (
    SELECT ip, MAX(timestamp) AS latest_time
    FROM device_status_log
    GROUP BY ip
) d2 ON d1.ip = d2.ip AND d1.timestamp = d2.latest_time;s
EOD);
// Display the data in an HTML table

 if ($query) {
     
     if ($query->execute()) {
            $rows = $query->fetchAll(PDO::FETCH_ASSOC);
            echo makeTable($rows);
 
 
 
 }
 else {
            echo "Error executing select query:<br>";
            print_r($query->errorInfo());
        }
     }
    // If $query is still false, then the problem probably comes from
    // one of the $db->prepare() calls. This can happen if the SQL 
    // syntax is incorrect (bad table/column name, syntax error, etc.)
    else {
        echo "Error executing select query:<br>";
        print_r($db->errorInfo());
    }

?>

<p>This was loaded at: <span id="time"></span></p>
<script>
  document.getElementById("time").textContent = new Date().toLocaleTimeString();
</script>

</body>
</html>