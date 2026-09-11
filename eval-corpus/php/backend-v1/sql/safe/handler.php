<?php
function handle(PDO $db) {
    $value = $_GET['value'];
    $statement = $db->prepare('SELECT * FROM records WHERE id=?');
    $statement->execute([$value]);
}
