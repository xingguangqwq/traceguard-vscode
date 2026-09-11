<?php
function handle(PDO $db) {
    $value = $_GET['value'];
    $command = $value;
    if ($value !== null) { $command = 'fixed'; } else { $command = 'fallback'; }
    system($command);
}
