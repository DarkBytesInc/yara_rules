rule Win_Trojan_Ciadoor_67
{
strings:
	$a0 = { b058b44e32b55662e6a5465dae599bfd838eb3e4fc9eab33afa8225ce660e7080bba247df217f0ba8dcab4d0ee9df050c7ca526e0ea0cccac529b37ac284f168c9403caf6eb18c17c3c92e67e226ce3ec2a95a13fa7a8f66d724c77e34bc9265b7348aee2e8dc484fa7d53c3be44644a3fa9ba53dababe7bf6a8c65befb0ed8c021becd875a5e45b07791419 }

condition:
	$a0
}

        