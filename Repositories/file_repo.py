from Model.models import File, db


class FileRepository:
    @staticmethod
    def create(original_name):
        new_file = File(original_name=original_name)
        db.session.add(new_file)
        db.session.commit()
        return new_file

    @staticmethod
    def update_state(file_id, new_state, enc_path=None):
        file = File.query.get(file_id)
        if file:
            file.state = new_state
            if enc_path:
                file.enc_file_path = enc_path
            db.session.commit()
            return file
        return None

    @staticmethod
    def get_by_id(file_id):
        return File.query.get(file_id)