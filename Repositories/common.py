from Model.models import db


def get_by_id(model_cls, entity_id):
    return db.session.get(model_cls, entity_id)


def assign_entity_fields(entity, ignore_none=False, **kwargs):
    for field, value in kwargs.items():
        if hasattr(entity, field) and (value is not None or not ignore_none):
            setattr(entity, field, value)


def update_entity(model_cls, entity_id, ignore_none=False, **kwargs):
    entity = db.session.get(model_cls, entity_id)
    if not entity:
        return None
    assign_entity_fields(entity, ignore_none=ignore_none, **kwargs)
    db.session.commit()
    return entity


def delete_entity(model_cls, entity_id):
    entity = db.session.get(model_cls, entity_id)
    if not entity:
        return False
    db.session.delete(entity)
    db.session.commit()
    return True
