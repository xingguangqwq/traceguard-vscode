<?php
function run($db) {
  $sql = $_GET["sql"];
  $page = max(1, (int) ($_GET["page"] ?? 1));
  return $db->query($sql);
}
