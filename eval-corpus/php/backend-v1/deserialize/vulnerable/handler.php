<?php
function handle(PDO $db) {
    $value = $_GET['value'];
    unserialize($value);
}
