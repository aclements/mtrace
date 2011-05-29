UGLY_TO_PRETTY = {

}

def pretty_name(name):
    if name in UGLY_TO_PRETTY:
        return UGLY_TO_PRETTY[name]
    s = name.split(':')
    if len(s) > 1:
        return name.split(':')[1]
    return name
