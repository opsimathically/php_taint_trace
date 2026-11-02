<?php

declare(strict_types=1);

$name = (string) ($_GET['name'] ?? 'guest');
header('X-PTT-Name: ' . $name);
printf("Hello %s", $name);
