rule Win_Trojan_Hupigon_1227
{
strings:
	$a0 = { b2323e44221108044dd903406e675adbcfc6de677b9c7f41bf877205bdee40be9d816f79c81cb6bb16e2c2de56ec1ad202de39016b80b6b906dae41b78e406db905eb7248b5c80de5c80e3980de76e42db9cc16f2f305bdee677bdfefffd7fbfef9f3fff377efa79fffbe7ddcdfdbe7bfcb773ace84bf8ef8348baf1f70dfd6dcdbe0ca5d4d509ff8c815981 }

condition:
	$a0
}

        