<?php
function handle(PDO $db) {
    $value = $_GET['value'];
    $command = 'fixed';
    if ($value !== null) { $command = $value; }
    system($command);
}
