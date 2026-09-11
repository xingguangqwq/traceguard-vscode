<?php
function handle(PDO $db) {
    $value = $_GET['value'];
    $alias = $value;
    $command = $alias;
    system($command);
}
