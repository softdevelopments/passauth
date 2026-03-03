export const removeKey = <T>(obj: T, key: keyof T) => {
  const { [key]: _removed, ...rest } = obj;

  return rest;
};
