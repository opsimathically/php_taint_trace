<?php

declare(strict_types=1);

$name = (string) ($_GET['name'] ?? 'guest');
printf('Hello %s', $name);
