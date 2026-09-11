<?php
function handle(PDO $db) {
    $value = $_GET['value'];
    curl_init($value);
}
