<?php
function handle(PDO $db) {
    $value = $_GET['value'];
    $command = 'fixed';
    $command = $value;
    system($command);
}
