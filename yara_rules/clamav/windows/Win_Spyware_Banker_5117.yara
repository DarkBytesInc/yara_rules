rule Win_Spyware_Banker_5117
{
strings:
	$a0 = { aa81271001bdecaba9aeeac8c9c1c2cca0a001c00a0391d5f3fde3ea8ad9fefeef0480115683aa8085c3171f0f72c4e0c388e330004e386f6a25051e0c0f021461300460ace19f22d79b02ce8a25be51162a32f231402a490359555580e1c2ba3d1cc10b23bfaa202f7b53032e982c44b215174b727e7c00189007fa03 }

condition:
	$a0
}

        