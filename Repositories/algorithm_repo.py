from Model.models import Algorithm, db


class AlgorithmRepository:
    @staticmethod
    def create(name, type):
        new_alg = Algorithm(name=name, type=type)
        db.session.add(new_alg)
        db.session.commit()
        return new_alg

    @staticmethod
    def get_all():
        return Algorithm.query.all()