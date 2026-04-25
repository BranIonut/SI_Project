from Model.models import Key, db


class KeyRepository:
    @staticmethod
    def create(
        name,
        algorithm_id,
        framework_id,
        key_type,
        key_value=None,
        key_path=None,
        public_key_value=None,
        private_key_value=None,
        is_active=True,
    ):
        key = Key(
            name=name,
            algorithm_id=algorithm_id,
            framework_id=framework_id,
            key_type=key_type,
            key_value=key_value,
            key_path=key_path,
            public_key_value=public_key_value,
            private_key_value=private_key_value,
            is_active=is_active,
        )
        db.session.add(key)
        db.session.commit()
        return key

    @staticmethod
    def get_by_id(key_id):
        return db.session.get(Key, key_id)

    @staticmethod
    def get_by_name(name):
        return Key.query.filter_by(name=name).first()

    @staticmethod
    def get_all():
        return Key.query.order_by(Key.created_at.desc()).all()

    @staticmethod
    def get_active():
        return Key.query.filter_by(is_active=True).order_by(Key.created_at.desc()).all()

    @staticmethod
    def update(key_id, **kwargs):
        key = db.session.get(Key, key_id)
        if not key:
            return None
        for field, value in kwargs.items():
            if hasattr(key, field):
                setattr(key, field, value)
        db.session.commit()
        return key

    @staticmethod
    def delete(key_id):
        key = db.session.get(Key, key_id)
        if not key:
            return False
        db.session.delete(key)
        db.session.commit()
        return True
