/**
 * 客户沟通记录接口定义
 */
export interface CommunicationRecord {
  /**
   * 沟通记录ID
   */
  id: string;

  /**
   * 沟通内容
   */
  content: string;

  /**
   * 沟通类型（如：电话、邮件、微信、面谈等）
   */
  type: string;

  /**
   * 沟通时间
   */
  timestamp: string;

  /**
   * 沟通人员（记录者）
   */
  createdBy: string;

  /**
   * 沟通结果或后续行动
   */
  outcome?: string;
}
