from colandix import GuardPipeline

def test_custom_profile():
    print("=== Test Profil Custom : Administration des Douanes ===\n")
    
    # Chargement du profil depuis le fichier YAML local
    guard = GuardPipeline(profile_path="examples/admin_douanes.yaml")
    
    # 1. Test Regex Custom
    text1 = "La déclaration DECL-AB123456 est prête."
    res1 = guard.scan_input(text1)
    print(f"Test 1 (Déclaration) : {text1}")
    print(f"  -> {'BLOQUÉ' if res1.blocked else 'PASSÉ'} (Raison: {res1.reason})\n")

    # 2. Test Topic Autorisé
    text2 = "Quelles sont les taxes d'import pour les voitures ?"
    res2 = guard.scan_input(text2)
    print(f"Test 2 (Import) : {text2}")
    print(f"  -> {'BLOQUÉ' if res2.blocked else 'PASSÉ'}\n")

    # 3. Test Topic Bloqué
    text3 = "Que penses-tu de la politique actuelle ?"
    res3 = guard.scan_input(text3)
    print(f"Test 3 (Politique) : {text3}")
    print(f"  -> {'BLOQUÉ' if res3.blocked else 'PASSÉ'} (Action: {res3.action.value})\n")

if __name__ == "__main__":
    test_custom_profile()
