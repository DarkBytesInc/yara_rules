rule Win_Trojan_SdBot_2145
{
strings:
	$a0 = { be8e2e984f76fd611e555ae079989b59f79b0815d0df1a99b377774634bb81fae6953e9f8bd02ea5fc0a32157eeedc0f8030edae52f78594229553e0c2d7e2adf5c316f2e643bd8a29a1ddc4f66e6cfea411aec5644db6c9a2109f4eb67e8efb3db6a8f610392b3a44bd97cd56434bbec77563aa9a1f1920974cf5931f7758b962bee4ca23ea388696ae1b0b493f10ffca7a }

condition:
	$a0
}

        