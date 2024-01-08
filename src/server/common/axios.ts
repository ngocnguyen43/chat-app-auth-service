import axios from 'axios';
import { config } from '../config';
import { NotFound } from '../libs/base-exception';

export const getService = async (name: string) => {
  try {
    const res = await axios.get(`http://${config["CONSUL_URL"]}/v1/catalog/service/${name}`).then(data => data.data);
    console.log(res)
    if (Array(res).length > 0) {
      return ((res)[0])['ServiceName'];
    } else {
      throw new NotFound();
    }
  } catch (error) {
    console.log(error);
    return '';
  }
};
