from Model.models import Framework, db
from Repositories.common import delete_entity, get_by_id, update_entity


class FrameworkRepository:
    @staticmethod
    def create(name, framework_type, version=None):
        framework = Framework(name=name, type=framework_type, version=version)
        db.session.add(framework)
        db.session.commit()
        return framework

    @staticmethod
    def get_by_id(framework_id):
        return get_by_id(Framework, framework_id)

    @staticmethod
    def get_by_name(name):
        framework = Framework.query.filter_by(name=name).first()
        if framework or name not in {"Custom", "Custom Educational"}:
            return framework
        return Framework.query.filter_by(name="Custom Educational / Legacy").first()

    @staticmethod
    def get_all():
        return Framework.query.order_by(Framework.name.asc()).all()

    @staticmethod
    def update(framework_id, **kwargs):
        return update_entity(Framework, framework_id, ignore_none=True, **kwargs)

    @staticmethod
    def delete(framework_id):
        return delete_entity(Framework, framework_id)
