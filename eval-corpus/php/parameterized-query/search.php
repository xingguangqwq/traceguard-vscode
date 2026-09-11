<?php
function run(PDO $db) {
  $name = $_GET["name"];
  $statement = $db->prepare("SELECT id FROM users WHERE name = ?");
  $statement->execute([$name]);
  return $statement->fetchAll();
}
