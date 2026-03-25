from Model.models import Framework, db


class FrameworkRepository:
    @staticmethod
    def create(name, version=None):
        fw = Framework(name=name, version=version)
        db.session.add(fw)
        db.session.commit()
        return fw

    @staticmethod
    def get_all():
        return Framework.query.all()