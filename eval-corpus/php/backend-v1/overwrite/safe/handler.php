<?php
function handle(PDO $db) {
    $value = $_GET['value'];
    $command = $value;
    $command = 'fixed';
    system($command);
}
