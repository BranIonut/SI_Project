from Model.models import Algorithm, Key, db
from sqlalchemy.orm import joinedload


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
        return (
            Key.query.options(joinedload(Key.algorithm), joinedload(Key.framework))
            .order_by(Key.created_at.desc(), Key.id.desc())
            .all()
        )

    @staticmethod
    def get_active():
        return (
            Key.query.options(joinedload(Key.algorithm), joinedload(Key.framework))
            .filter_by(is_active=True)
            .order_by(Key.created_at.desc(), Key.id.desc())
            .all()
        )

    @staticmethod
    def count_keys():
        return Key.query.count()

    @staticmethod
    def get_keys_paginated(page, page_size):
        safe_page = max(int(page or 1), 1)
        safe_page_size = max(int(page_size or 10), 1)
        return (
            Key.query.options(joinedload(Key.algorithm), joinedload(Key.framework))
            .order_by(Key.created_at.desc(), Key.id.desc())
            .offset((safe_page - 1) * safe_page_size)
            .limit(safe_page_size)
            .all()
        )

    @staticmethod
    def _compatible_keys_query(framework_id, algorithm):
        query = (
            Key.query.options(joinedload(Key.algorithm), joinedload(Key.framework))
            .filter(Key.is_active.is_(True), Key.framework_id == framework_id)
        )
        if not algorithm:
            return query.filter(Key.id == -1)
        if algorithm.type == "hybrid":
            return query.join(Algorithm, Key.algorithm_id == Algorithm.id).filter(Algorithm.name == "RSA-2048")
        return query.filter(Key.algorithm_id == algorithm.id)

    @staticmethod
    def count_compatible_active_keys(framework_id, algorithm):
        return KeyRepository._compatible_keys_query(framework_id, algorithm).count()

    @staticmethod
    def get_compatible_active_keys_paginated(framework_id, algorithm, page, page_size):
        safe_page = max(int(page or 1), 1)
        safe_page_size = max(int(page_size or 10), 1)
        return (
            KeyRepository._compatible_keys_query(framework_id, algorithm)
            .order_by(Key.created_at.desc(), Key.id.desc())
            .offset((safe_page - 1) * safe_page_size)
            .limit(safe_page_size)
            .all()
        )

    @staticmethod
    def resolve_rsa_algorithm():
        return Algorithm.query.filter_by(name="RSA-2048").first()

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
