rule Win_Trojan_Hupigon_892
{
strings:
	$a0 = { 944adaa109fab8fa36b06ebe09318db819e5c7e2a8954945388f7dfbe066d5c776d400a50fbfa8e1edd9cde75aeee86fd58722937decdc82c4c1d81e481d62e5bb43f724a63db96c93c2822bff93ba7d32e168c20432fd91f2eafb8be55051 }

condition:
	$a0
}

        
