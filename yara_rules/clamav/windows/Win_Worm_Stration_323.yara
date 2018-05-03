rule Win_Worm_Stration_323
{
strings:
	$a0 = { 87434fb54ea7fdc5deb24fcceedcce0538bde9e2adeff9eee14a1e23dff9f69d2a05a6ed7e104c6a30b3ac31b9680474d8b6e31eae4d275fcc4b2f37500b1828f7cbf6feeb3242ab5abe3f67f13d46bc4a3ff699489051de14671962457e1dce }

condition:
	$a0
}

        
