<?php
require_once __DIR__ . '/helper.php';
function handle(PDO $db) {
    $value = $_GET['value'];
    runCommand('fixed');
}
