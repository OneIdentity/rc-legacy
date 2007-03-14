<?php

require "vas.php";

function printCode($var)
{
  echo "    Error code: ";
  echo vas_err();
  echo "\n    ";
  var_dump($var);
}

echo "Allocate ctx\n";
$ctx = vas_ctx_alloc();
printCode($ctx);

echo "Allocate id\n";
$id = vas_id_alloc($ctx, "Daniel");
printCode($id);

echo "Allocate attrs\n";
$attrs = vas_attrs_alloc($ctx, $id);
printCode($attrs);

?>
