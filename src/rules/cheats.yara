rule HitBox_editing {
    meta:
        description = "Обнаружена возможность изменения хитбокса игрока"
        category = "hitbox"
        severity = 4
        details = "Найден класс для изменения хитбокса"

    strings:
        $hb1 = "method_5857" nocase
        $hb2 = "setBoundingBox" nocase
        $hb3 = "getDimensions" nocase
        $hb4 = "func_174826_a" nocase
        $hb5 = "m_20011_" nocase
        $hb6 = "AxisAlignedBB" nocase
        $hb7 = ".a(new dci" nocase

    condition:
        any of them
}

rule Crystal_Optimizer {
    meta:
        description = "Обнаружена возможность функционала Crystal Optimizer"
        category = "crystal_optimizer"
        severity = 3
        details = "Часто оно сливается вместе с AutoAttack"

    strings:
        $co1 = "class_239" nocase
        $co2 = "HitResult" nocase
        $co3 = "class_1511" nocase
        $co4 = "EndCrystalEntity" nocase
        $co5 = "RayTraceResult" nocase
        $co6 = "EntityRayTraceResult" nocase
        $co7 = "EntityHitResult" nocase
        $co8 = "EnderCrystalentity" nocase
        $co9 = "EndCrystal" nocase
        $co10 = "dcl" nocase
        $co11 = "dck" nocase
        $co12 = "bbq" nocase
    
    condition:
        any of them
}

rule AutoAttack {
    meta:
        description = "Обнаружена возможность функционала AutoAttack"
        category = "autoattack"
        severity = 3
        details = "Часто оно сливается вместе с Crystal Optimizer"

    strings:
        $aa1 = /class_239[^0-9]/ nocase //сделать так для всех классов и функций
        $aa2 = "HitResult" nocase
        $aa3 = "RayTraceResult" nocase
        $aa4 = "EntityRayTraceResult" nocase
        $aa5 = "EntityHitResult" nocase
        $aa6 = "dcl" nocase
        $aa7 = "dck" nocase
    
    condition:
        any of them
}

rule Swapper {
    meta:
        description = "Обнаружена возможность функционала swapper"
        category = "swapper"
        severity = 1
        details = "Попадается почти в каждом моде"

    strings:
        $sw1 = "class_1799" nocase
        $sw2 = "ItemStack" nocase

    condition:
        any of them
}