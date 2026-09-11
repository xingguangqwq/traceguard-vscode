<?php
function handle(PDO $db) {
    $value = $_GET['value'];
    $db->query("SELECT * FROM records WHERE id=" . $value);
}
