from Model.models import app, db
from Repositories.framework_repo import FrameworkRepository
from Repositories.algorithm_repo import AlgorithmRepository
from Repositories.file_repo import FileRepository
from Repositories.performance_repo import PerformanceRepository


def run_crud_tests():
    with app.app_context():
        print("\n=== STARTING CRUD TESTS ===")

        print("1. Inserting data into the database...")

        if not FrameworkRepository.get_all():
            fw = FrameworkRepository.create(name="OpenSSL", version="3.0.2")
            alg_aes = AlgorithmRepository.create(name="AES-256-CBC", type="Symmetric")
            alg_rsa = AlgorithmRepository.create(name="RSA-2048", type="Asymmetric")
            print(f"   -> Added Framework: {fw.name} and Algorithms: {alg_aes.name}, {alg_rsa.name}")
        else:
            print("   -> Base data already exists.")

        test_file = FileRepository.create(original_name="secret_document.docx")
        print(f"   -> File created: {test_file.original_name} (State: {test_file.state})")

        print("\n2. Updating file state...")
        updated_file = FileRepository.update_state(
            file_id=test_file.id,
            new_state="Encrypted",
            enc_path="/encrypted/secret_document.enc"
        )
        print(f"   -> File updated! New state: {updated_file.state} | Path: {updated_file.enc_file_path}")

        print("\n3. Final database validation...")
        file_check = FileRepository.get_by_id(test_file.id)
        if file_check:
            print(f"   -> Found in DB: ID {file_check.id} | Name: {file_check.original_name}")

        print("=== TESTS COMPLETED SUCCESSFULLY! ===\n")


if __name__ == '__main__':
    run_crud_tests()