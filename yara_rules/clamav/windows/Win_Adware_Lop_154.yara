rule Win_Adware_Lop_154
{
strings:
	$a0 = { 24dd612985ccc3c8a86ce2e6190886dbc33f6edccce2dd4ee614e46c9eeb0c079042cab1cecfb3cd7e8cbf521f7975566f174731f622ca0adc76d3d07a107997a0fe353b31fafb362593cf57898b521a5738edd3ea89c65a96142e383cfe7b3aecdc }

condition:
	$a0
}

        
