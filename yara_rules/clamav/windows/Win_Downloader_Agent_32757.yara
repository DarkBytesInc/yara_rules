rule Win_Downloader_Agent_32757
{
strings:
	$a0 = { 96d101105d8945e49db1b45b80c5b15f5e80c681c9c380c5405580e97e89e583ec1c5680c1ac5780eaff539c80ea825583ec0480e644c7042400000000b6f080cec2e8116cffff5d80c5918945e85583ec0480e106c704240000000080e101ff1580a001105d8945e49d5b80e6005f80c5255e80f62ac9c380e1065589e580c55b83ec405657539c837d08007402eb05e9aa0100 }

condition:
	$a0
}

        