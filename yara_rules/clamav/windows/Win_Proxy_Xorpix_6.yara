rule Win_Proxy_Xorpix_6
{
strings:
	$a0 = { 4b4f18f493f741de1f18e8d454544fdeb0df8660d818c40fb44fac0f1db04565d820cf4e559c881f7cfc2dcf9f41744e4c4268430e645a484820cfdff260492e5843485344db326cd8301f1c3f08548e1cf8a59db7271ce4bf1cd80ec8f22ced9e4cbcbe0ea8429ccff22ccf498c4a805a682dcff22c534c544047060c1be4ae34280f180fd7abde751c08bf1bf46f1be42fcfd20678 }

condition:
	$a0
}

        