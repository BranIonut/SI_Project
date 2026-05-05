from Model.models import Algorithm, db
from Repositories.common import delete_entity, get_by_id, update_entity


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
        return get_by_id(Algorithm, algorithm_id)

    @staticmethod
    def get_by_name(name):
        return Algorithm.query.filter_by(name=name).first()

    @staticmethod
    def get_all():
        return Algorithm.query.order_by(Algorithm.name.asc()).all()

    @staticmethod
    def update(algorithm_id, **kwargs):
        return update_entity(Algorithm, algorithm_id, ignore_none=True, **kwargs)

    @staticmethod
    def delete(algorithm_id):
        return delete_entity(Algorithm, algorithm_id)
