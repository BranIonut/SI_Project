from Model.models import Framework, db


class FrameworkRepository:
    @staticmethod
    def create(name, framework_type, version=None):
        framework = Framework(name=name, type=framework_type, version=version)
        db.session.add(framework)
        db.session.commit()
        return framework

    @staticmethod
    def get_by_id(framework_id):
        return db.session.get(Framework, framework_id)

    @staticmethod
    def get_by_name(name):
        return Framework.query.filter_by(name=name).first()

    @staticmethod
    def get_all():
        return Framework.query.order_by(Framework.name.asc()).all()

    @staticmethod
    def update(framework_id, **kwargs):
        framework = db.session.get(Framework, framework_id)
        if not framework:
            return None
        for field, value in kwargs.items():
            if hasattr(framework, field) and value is not None:
                setattr(framework, field, value)
        db.session.commit()
        return framework

    @staticmethod
    def delete(framework_id):
        framework = db.session.get(Framework, framework_id)
        if not framework:
            return False
        db.session.delete(framework)
        db.session.commit()
        return True
