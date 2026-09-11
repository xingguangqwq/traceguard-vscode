<?php
function handle(PDO $db) {
    $value = $_GET['value'];
    $alias = $value;
    $command = 'fixed';
    system($command);
}
