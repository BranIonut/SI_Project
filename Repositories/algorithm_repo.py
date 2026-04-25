from Model.models import Algorithm, db


class AlgorithmRepository:
    @staticmethod
    def create(name, type, key_size, mode=None, framework_id=None, description=None):
        new_alg = Algorithm(
            name=name,
            type=type,
            key_size=key_size,
            mode=mode,
            framework_id=framework_id,
            description=description,
        )
        db.session.add(new_alg)
        db.session.commit()
        return new_alg

    @staticmethod
    def get_by_id(algorithm_id):
        return db.session.get(Algorithm, algorithm_id)

    @staticmethod
    def get_by_name(name):
        return Algorithm.query.filter_by(name=name).first()

    @staticmethod
    def get_all():
        return Algorithm.query.order_by(Algorithm.name.asc()).all()

    @staticmethod
    def update(algorithm_id, **kwargs):
        algorithm = db.session.get(Algorithm, algorithm_id)
        if not algorithm:
            return None
        for field, value in kwargs.items():
            if hasattr(algorithm, field) and value is not None:
                setattr(algorithm, field, value)
        db.session.commit()
        return algorithm

    @staticmethod
    def delete(algorithm_id):
        algorithm = db.session.get(Algorithm, algorithm_id)
        if not algorithm:
            return False
        db.session.delete(algorithm)
        db.session.commit()
        return True